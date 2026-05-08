# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Remediation Engine API Router.
Playbooks, AI copilot, and effort estimation.
"""
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org
from app.models.finding import Finding
from app.models.membership import Membership
from app.models.user import User
from app.services.remediation import (
    estimate_remediation,
    get_all_playbooks,
    get_playbook,
)

router = APIRouter(prefix="/remediation", tags=["remediation"])


# --- Playbooks ---

@router.get("/playbooks")
async def list_playbooks():
    """List all available remediation playbooks."""
    playbooks = get_all_playbooks()
    return {
        "total": len(playbooks),
        "playbooks": {k: {
            "title": v["title"],
            "category": v["category"],
            "effort": v["effort"],
            "cost": v["cost"],
            "time_minutes": v["time_minutes"],
            "nis2_article": v["nis2_article"],
        } for k, v in playbooks.items()},
    }


@router.get("/playbooks/{playbook_id}")
async def get_playbook_detail(playbook_id: str):
    """Get full playbook with configs and steps."""
    playbooks = get_all_playbooks()
    pb = playbooks.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")
    return {"id": playbook_id, **pb}


@router.get("/for-finding/{finding_id}")
async def get_remediation_for_finding(
    finding_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Get matching remediation playbook for a specific finding."""
    user, membership = current_org
    finding = await db.get(Finding, finding_id)
    if not finding or finding.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    playbook = get_playbook(finding.category, finding.message)
    return {
        "finding": {
            "id": str(finding.id),
            "severity": finding.severity,
            "category": finding.category,
            "message": finding.message,
            "target": finding.target,
        },
        "playbook": playbook,
        "has_playbook": playbook is not None,
    }


# --- Effort Estimator ---

@router.get("/estimate/{scan_id}")
async def estimate_scan_remediation(
    scan_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Calculate remediation effort and cost for all findings in a scan."""
    user, membership = current_org

    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.organization_id == membership.organization_id,
            Finding.status.in_(["open", "acknowledged", "in_progress"]),
        )
    )
    findings = result.scalars().all()

    if not findings:
        return {"scan_id": str(scan_id), "total_findings": 0, "message": "No open findings"}

    finding_dicts = [
        {
            "message": f.message,
            "severity": f.severity,
            "category": f.category,
            "remediation_effort": f.remediation_effort or "Medium",
        }
        for f in findings
    ]

    estimate = estimate_remediation(finding_dicts)
    estimate["scan_id"] = str(scan_id)
    return estimate


# --- AI Copilot ---

class ExplainRequest(BaseModel):
    model: str = Field(default="auto", description="LLM model to use")
    context: Optional[str] = Field(None, description="Additional infrastructure context")


@router.post("/explain/{finding_id}")
async def explain_finding(
    finding_id: uuid.UUID,
    payload: ExplainRequest = ExplainRequest(),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """AI-powered finding explanation with personalized remediation commands.
    Connects to local LLM (Ollama/LM Studio) or OpenAI."""
    user, membership = current_org
    finding = await db.get(Finding, finding_id)
    if not finding or finding.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Build context
    playbook = get_playbook(finding.category, finding.message)

    prompt = f"""You are a NIS2 cybersecurity remediation expert. Explain this finding and provide actionable remediation steps.

## Finding
- **Severity**: {finding.severity}
- **Category**: {finding.category}
- **Message**: {finding.message}
- **Target**: {finding.target}
- **Technical Detail**: {finding.technical_detail or 'N/A'}
- **NIS2 Article**: {finding.compliance_article or 'Art. 21'}
{f'- **Infrastructure Context**: {payload.context}' if payload.context else ''}

## Instructions
1. Explain WHY this is a risk in plain language (for a CISO)
2. Provide exact, copy-paste commands to fix it
3. Include commands for Nginx, Apache, or Linux as appropriate
4. Reference the specific NIS2 article and ENISA guidance
5. Estimate time to fix

Respond in a structured format with clear headings."""

    # Try to connect to LLM
    llm_url = os.environ.get("LLM_API_URL", "http://localhost:1234/v1")
    openai_key = os.environ.get("OPENAI_API_KEY")

    explanation = None

    # Try local LLM first (Ollama / LM Studio)
    if not openai_key or payload.model != "openai":
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{llm_url}/chat/completions",
                    json={
                        "model": payload.model if payload.model != "auto" else "default",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,
                        "max_tokens": 2000,
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        explanation = data["choices"][0]["message"]["content"]
        except Exception:
            # P2-01 audit fix: log LLM connection failure instead of
            # swallowing silently. The fallback to OpenAI / playbook
            # still fires, but we now have visibility into why.
            import logging
            logging.getLogger(__name__).debug(
                "Local LLM call failed for finding %s, trying fallback", finding_id, exc_info=True,
            )

    # Fallback to OpenAI
    if not explanation and openai_key:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {openai_key}"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,
                        "max_tokens": 2000,
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        explanation = data["choices"][0]["message"]["content"]
        except Exception:
            # P2-01 audit fix: same as the local LLM handler above.
            import logging
            logging.getLogger(__name__).debug(
                "OpenAI call failed for finding %s, falling back to playbook", finding_id, exc_info=True,
            )

    # Final fallback: use playbook
    if not explanation:
        if playbook:
            explanation = _format_playbook_as_explanation(finding, playbook)
        else:
            explanation = f"**{finding.severity}: {finding.message}**\n\n" \
                          f"Target: `{finding.target}`\n\n" \
                          f"This finding relates to {finding.compliance_article or 'NIS2 Art. 21'}.\n\n" \
                          f"**Recommended action**: {finding.remediation or 'Review and remediate this finding.'}"

    return {
        "finding_id": str(finding.id),
        "explanation": explanation,
        "source": "llm" if explanation and playbook is None else "playbook+llm" if explanation else "playbook",
        "playbook_available": playbook is not None,
    }


def _format_playbook_as_explanation(finding, playbook: dict) -> str:
    """Format a playbook as a readable explanation when LLM is unavailable."""
    lines = [
        f"# {playbook['title']}",
        f"\n**Severity**: {finding.severity} | **NIS2 Reference**: {playbook['nis2_article']}",
        f"\n**Risk if ignored**: {playbook['risk_if_ignored']}",
        f"\n**Estimated effort**: {playbook['effort']} ({playbook['time_minutes']} minutes) | **Cost**: {playbook['cost']}",
        "\n## Steps",
    ]
    for i, step in enumerate(playbook["steps"], 1):
        lines.append(f"{i}. {step}")

    if playbook.get("configs"):
        lines.append("\n## Configuration Examples")
        for server, config in playbook["configs"].items():
            lines.append(f"\n### {server.replace('_', ' ').title()}")
            lines.append(f"```\n{config}\n```")

    return "\n".join(lines)
