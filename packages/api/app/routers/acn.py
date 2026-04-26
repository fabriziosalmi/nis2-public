# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
ACN Export and Compliance Deadlines API.

Endpoints:
- /acn-export: Generate ACN-compatible JSON for Determina 127437 and Art. 23
- /deadlines: Compliance timeline with real NIS2 D.Lgs 138/2024 deadlines
- /csirt/emergency: "Red Button" - instant CSIRT Early Warning payload generator
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user_org

router = APIRouter(tags=["acn"])


# -------------------------------------------------------------------------
# Compliance Deadlines — "Timeline della Morte"
# -------------------------------------------------------------------------

# Real NIS2 D.Lgs 138/2024 deadlines
NIS2_DEADLINES = [
    {
        "id": "csirt_referent",
        "title": "Nomina Referente CSIRT",
        "description": "Obbligo di designazione del referente per le comunicazioni con CSIRT Italia.",
        "deadline": "2026-12-31",
        "article": "Art. 23 D.Lgs 138/2024",
        "category": "governance",
    },
    {
        "id": "notification_24h",
        "title": "Obbligo notifica incidenti 24h",
        "description": "Inizio obbligo di Early Warning entro 24 ore dal rilevamento di incidente significativo.",
        "deadline": "2027-01-01",
        "article": "Art. 23 D.Lgs 138/2024",
        "category": "incident_response",
    },
    {
        "id": "security_measures_base",
        "title": "Misure di sicurezza di base",
        "description": "Implementazione completa delle misure di sicurezza di base definite dalla Determina ACN 127434/2026.",
        "deadline": "2027-07-01",
        "article": "Determina ACN 127434/2026",
        "category": "technical",
    },
    {
        "id": "vendor_inventory",
        "title": "Inventario fornitori rilevanti",
        "description": "Elencazione completa dei fornitori rilevanti per la sicurezza (Art. 18).",
        "deadline": "2027-07-01",
        "article": "Determina ACN 127437/2026, Art. 18",
        "category": "supply_chain",
    },
    {
        "id": "bia_completion",
        "title": "Business Impact Analysis",
        "description": "Completamento BIA secondo il modello standardizzato ACN.",
        "deadline": "2027-07-01",
        "article": "Art. 21(c) D.Lgs 138/2024",
        "category": "governance",
    },
    {
        "id": "risk_assessment",
        "title": "Risk Assessment completo",
        "description": "Analisi dei rischi aggiornata secondo Art. 21(a) con metodologia documentata.",
        "deadline": "2027-07-01",
        "article": "Art. 21(a) D.Lgs 138/2024",
        "category": "governance",
    },
]


@router.get("/deadlines")
async def get_deadlines():
    """
    NIS2 compliance timeline with countdown.
    Returns real deadlines from D.Lgs 138/2024 and Determine ACN,
    with days remaining and urgency classification.
    """
    now = datetime.now(timezone.utc)
    enriched = []

    for d in NIS2_DEADLINES:
        deadline_dt = datetime.fromisoformat(d["deadline"]).replace(tzinfo=timezone.utc)
        delta = deadline_dt - now
        days_remaining = delta.days

        if days_remaining < 0:
            urgency = "overdue"
        elif days_remaining <= 90:
            urgency = "critical"
        elif days_remaining <= 180:
            urgency = "urgent"
        elif days_remaining <= 365:
            urgency = "warning"
        else:
            urgency = "on_track"

        enriched.append({
            **d,
            "days_remaining": days_remaining,
            "urgency": urgency,
            "months_remaining": round(days_remaining / 30.44, 1),
        })

    enriched.sort(key=lambda x: x["days_remaining"])

    return {
        "reference_date": now.isoformat(),
        "deadlines": enriched,
        "overdue_count": sum(1 for d in enriched if d["urgency"] == "overdue"),
        "critical_count": sum(1 for d in enriched if d["urgency"] == "critical"),
    }


# -------------------------------------------------------------------------
# CSIRT Emergency — "Tasto Rosso" (Art. 23)
# -------------------------------------------------------------------------

class EmergencyIncidentRequest(BaseModel):
    """Minimal fields for panic-mode incident declaration."""
    what_happened: str
    affected_services: str
    is_ongoing: bool = True
    estimated_users_affected: Optional[int] = None
    detected_at: Optional[datetime] = None


@router.post("/csirt/emergency")
async def csirt_emergency_payload(
    data: EmergencyIncidentRequest,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """
    CSIRT "Red Button" — Generate Art. 23 Early Warning payload.

    Under stress (ransomware at 3 AM), the operator fills 3 fields.
    The system generates the complete Early Warning payload using
    the latest asset data from the database. Guarantees the 24h SLA.
    """
    user, org_id = auth
    now = datetime.now(timezone.utc)
    detected = data.detected_at or now

    # Fetch org name
    from app.models.organization import Organization
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    org_name = org.name if org else "Unknown Organization"

    # Fetch latest asset inventory
    from app.models.asset import Asset
    asset_result = await db.execute(
        select(Asset).where(Asset.organization_id == org_id)
    )
    assets = asset_result.scalars().all()
    asset_inventory = [
        {"name": a.name, "target": a.target_value, "type": a.target_type}
        for a in assets
    ]

    # Generate Early Warning payload (ACN CSIRT format)
    early_warning = {
        "schema_version": "1.0",
        "document_type": "early_warning",
        "generated_at": now.isoformat(),
        "generator": "NIS2 Compliance Platform (nis2-public)",

        "reporting_entity": {
            "organization_name": org_name,
            "organization_id": str(org_id),
            "contact_email": user.email if hasattr(user, 'email') else None,
        },

        "incident": {
            "detection_timestamp": detected.isoformat(),
            "early_warning_deadline": (detected + timedelta(hours=24)).isoformat(),
            "notification_deadline": (detected + timedelta(hours=72)).isoformat(),
            "final_report_deadline": (detected + timedelta(days=30)).isoformat(),

            "description": data.what_happened,
            "affected_services": data.affected_services,
            "is_ongoing": data.is_ongoing,
            "estimated_users_affected": data.estimated_users_affected,

            "hours_remaining_early_warning": max(
                0, round((detected + timedelta(hours=24) - now).total_seconds() / 3600, 1)
            ),
            "hours_remaining_notification": max(
                0, round((detected + timedelta(hours=72) - now).total_seconds() / 3600, 1)
            ),
        },

        "asset_inventory_snapshot": asset_inventory,

        "classification": {
            "severity": "to_be_determined",
            "csirt_taxonomy": "to_be_classified",
            "cross_border_impact": False,
            "supply_chain_impact": False,
        },

        "instructions": {
            "next_step": "Submit this payload to CSIRT Italia within the early_warning_deadline.",
            "notification_portal": "https://www.csirt.gov.it/",
            "note": "This is an auto-generated Early Warning. Complete incident details in the full notification within 72 hours.",
        },
    }

    return early_warning


# -------------------------------------------------------------------------
# ACN Export — Determina 127437 compliant data export
# -------------------------------------------------------------------------

@router.get("/acn-export/art18")
async def export_art18_vendors(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """
    Export vendor inventory in ACN Determina 127437 compatible format.
    Downloads as structured JSON ready for ACN portal data entry.
    """
    user, org_id = auth

    from app.models.vendor import Vendor
    result = await db.execute(
        select(Vendor).where(
            Vendor.organization_id == org_id,
            Vendor.acn_rilevanza_art18,
        ).order_by(Vendor.criticality)
    )
    vendors = result.scalars().all()

    from app.models.organization import Organization
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()

    export = {
        "schema_version": "1.0",
        "document_type": "acn_art18_vendor_inventory",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "NIS2 Compliance Platform (nis2-public)",
        "reference": "Determina ACN 127437/2026 — Art. 18 D.Lgs 138/2024",

        "reporting_entity": {
            "organization_name": org.name if org else "Unknown",
            "organization_id": str(org_id),
        },

        "vendor_inventory": [
            {
                "nome_fornitore": v.name,
                "tipologia": v.vendor_type,
                "livello_criticita": v.criticality,
                "servizi_forniti": v.services_provided,
                "livello_accesso_dati": v.data_access_level,
                "localizzazione_geografica": v.geographic_location,
                "certificazioni_sicurezza": v.has_security_certification,
                "data_ultimo_audit": v.last_audit_date.isoformat() if v.last_audit_date else None,
                "codice_servizio_acn": v.acn_codice_servizio,
                "stato": v.status,
                "punteggio_sicurezza": v.security_score,
                "clausole_contrattuali": v.security_clauses,
            }
            for v in vendors
        ],

        "summary": {
            "total_vendors_art18": len(vendors),
            "critical_count": sum(1 for v in vendors if v.criticality == 1),
            "without_certification": sum(1 for v in vendors if not v.has_security_certification),
            "without_audit": sum(1 for v in vendors if not v.last_audit_date),
        },
    }

    return export


@router.get("/acn-export/bia")
async def export_bia(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """
    Export BIA data in ACN-compatible format.
    Ready for future ACN BIA template integration.
    """
    user, org_id = auth

    from app.models.bia import BusinessProcess
    result = await db.execute(
        select(BusinessProcess)
        .where(BusinessProcess.organization_id == org_id)
        .order_by(BusinessProcess.criticality_level)
    )
    processes = result.scalars().all()

    from app.models.organization import Organization
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()

    export = {
        "schema_version": "1.0",
        "document_type": "acn_bia_export",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "NIS2 Compliance Platform (nis2-public)",
        "reference": "Art. 21(c) D.Lgs 138/2024 — Business Continuity",

        "reporting_entity": {
            "organization_name": org.name if org else "Unknown",
            "organization_id": str(org_id),
        },

        "business_processes": [
            {
                "nome_processo": p.name,
                "descrizione": p.description,
                "responsabile": p.process_owner,
                "dipartimento": p.department,
                "livello_criticita": p.criticality_level,
                "rto_ore": p.rto_hours,
                "rpo_ore": p.rpo_hours,
                "mtpd_ore": p.mtpd_hours,
                "impatto_finanziario": p.impact_financial,
                "impatto_operativo": p.impact_operational,
                "impatto_reputazionale": p.impact_reputational,
                "impatto_regolatorio": p.impact_regulatory,
                "impatto_sicurezza": p.impact_safety,
                "servizio_essenziale_acn": p.acn_servizio_essenziale,
                "codice_servizio_acn": p.acn_codice_servizio,
                "settore_acn": p.acn_settore,
                "piano_continuita": p.has_bcp,
                "piano_disaster_recovery": p.has_drp,
            }
            for p in processes
        ],

        "summary": {
            "total_processes": len(processes),
            "mission_critical": sum(1 for p in processes if p.criticality_level == 1),
            "essential_services": sum(1 for p in processes if p.acn_servizio_essenziale),
            "without_bcp": sum(1 for p in processes if not p.has_bcp),
            "without_drp": sum(1 for p in processes if not p.has_drp),
            "without_rto": sum(1 for p in processes if not p.rto_hours),
        },
    }

    return export
