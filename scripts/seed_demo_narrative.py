# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Narrative enrichment for the LinkedIn demo video.

`seed_demo.py` builds the "fleet" (10 fictitious orgs + assets + scans +
findings). This script layers on top of it the three story beats the
60-second demo needs and that the base seed does NOT create:

  1. GOVERNANCE checklist (30 items) on every demo org — so the live
     `POST /governance/sync-risk` click has something to escalate on
     camera. Only the administrative items (scoping / ACN / board /
     training) are pre-marked done/in-progress; every Art. 21.2.x item
     is left `not_started` so the scanner findings visibly escalate them.

  2. Live INCIDENTS with the Art. 23 clock running. Deadlines are
     computed relative to *seed time*, so re-run this script right
     before filming to get a fresh, tense countdown:
       - Gamma Power  → critical OT intrusion, ~32 h to the 72 h
         notification deadline, early warning already sent  (THE hero clock)
       - Eta Water    → fresh telemetry intrusion, ~18 h to the 24 h
         early-warning deadline, not yet sent  (the urgent one)
       - Beta Bank    → closed data breach, full lifecycle  (realism)

  3. NOTIFICATION channels (Slack + email) on the hero orgs — so the
     "alert dispatched" beat is backed by real configured channels.

Plus VENDORS (Art. 18) and BIA processes on the hero orgs to make the
exported PDF report look full.

LEGAL NOTE — every identifier here is fictitious, consistent with
seed_demo.py: RFC 2606 (.example) domains, RFC 5737 documentation IPs,
placeholder names. Slack/webhook URLs point at example.com and are
non-functional.

Idempotent: it deletes the rows it manages for the target orgs, then
recreates them. Safe to re-run.

Run (after seed_demo.py):
  docker compose -f infra/docker/docker-compose.dev.yml exec api \
    python /app/scripts/seed_demo_narrative.py
"""
import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "api"))


# ── Story configuration ────────────────────────────────────────────────
# Governance items that a "work-in-progress" org would already have
# closed. Everything else (all the Art. 21.2.x technical items the
# scanner findings map to) stays not_started so sync-risk escalates them.
GOV_DONE = {"G-01", "G-02"}          # scoping + ACN registration
GOV_IN_PROGRESS = {"G-03", "G-04"}   # board responsibility + training

# Every demo org gets the checklist; these get the full narrative overlay.
HERO_SLUGS = ["gamma-power", "eta-water", "beta-bank"]

# The 10 slugs created by seed_demo.py (the "fleet"). The MSSP operator
# below is made a member of every one of these so a single login shows
# all ten clients in the org switcher — the canale-first demo protagonist.
DEMO_SLUGS = [
    "alpha-medical", "beta-bank", "gamma-power", "delta-foods", "epsilon-telco",
    "zeta-rail", "demoville", "eta-water", "theta-consulting", "iota-confectionery",
]
MSSP_OPERATOR_EMAIL = "operator@mssp-demo.example"


def _incidents_for(now, org_slug, org, user_id, asset_ids):
    """Return the incident dicts for a hero org, deadlines relative to `now`."""
    if org_slug == "gamma-power":
        detected = now - timedelta(hours=40)
        return [
            dict(
                organization_id=org.id,
                reported_by=user_id,
                title="Sospetto accesso non autorizzato all'interfaccia SCADA",
                incident_type="apt",
                severity="critical",
                status="early_warning_sent",
                detected_at=detected,
                early_warning_deadline=detected + timedelta(hours=24),
                early_warning_sent_at=detected + timedelta(hours=20),
                notification_deadline=detected + timedelta(hours=72),   # ≈ now + 32h
                final_report_deadline=detected + timedelta(days=30),
                description=(
                    "Rilevati accessi anomali all'interfaccia web SCADA esposta "
                    "su internet (scada.gamma-power.example). Pattern compatibile "
                    "con enumerazione credenziali su controller Modbus. Segmento OT "
                    "potenzialmente esposto. Early warning al CSIRT inviato; "
                    "notifica di dettaglio (72h) in preparazione."
                ),
                affected_systems="SCADA web interface, controller Modbus, DMZ industriale",
                affected_asset_ids=asset_ids[:3],
                impact_category="operational",
                estimated_impact_level=2,  # severe
                cross_border=False,
                supply_chain_impact=True,
                users_affected_count=None,
                indicators_of_compromise={
                    "ips": ["198.51.100.77"],
                    "domains": ["c2.example"],
                },
                timeline_events=[
                    {"at": (detected).isoformat(), "event": "Anomalia rilevata dal SIEM"},
                    {"at": (detected + timedelta(hours=20)).isoformat(),
                     "event": "Early warning inviato al CSIRT (Art. 23, 24h)"},
                ],
                containment_actions="Interfaccia SCADA isolata dalla rete pubblica; regole firewall applicate al segmento OT.",
                csirt_taxonomy_code="INTRUSION-ATTEMPT",
            ),
        ]
    if org_slug == "eta-water":
        detected = now - timedelta(hours=6)
        return [
            dict(
                organization_id=org.id,
                reported_by=user_id,
                title="Tentativo di intrusione sulla telemetria impianti (Telnet)",
                incident_type="other",
                severity="high",
                status="detected",
                detected_at=detected,
                early_warning_deadline=detected + timedelta(hours=24),   # ≈ now + 18h
                early_warning_sent_at=None,
                notification_deadline=detected + timedelta(hours=72),
                final_report_deadline=detected + timedelta(days=30),
                description=(
                    "Login Telnet ripetuti verso l'endpoint di telemetria "
                    "(203.0.113.50). Servizio Telnet legacy ancora attivo. "
                    "Valutazione impatto in corso; early warning non ancora inviato."
                ),
                affected_systems="Telemetria impianti, rete SCADA depuratori",
                affected_asset_ids=asset_ids[:2],
                impact_category="operational",
                estimated_impact_level=3,
                supply_chain_impact=False,
                csirt_taxonomy_code="INTRUSION-ATTEMPT",
            ),
        ]
    if org_slug == "beta-bank":
        detected = now - timedelta(days=20)
        return [
            dict(
                organization_id=org.id,
                reported_by=user_id,
                title="Esfiltrazione limitata di dati da form di contatto",
                incident_type="data_breach",
                severity="medium",
                status="closed",
                detected_at=detected,
                early_warning_deadline=detected + timedelta(hours=24),
                early_warning_sent_at=detected + timedelta(hours=6),
                notification_deadline=detected + timedelta(hours=72),
                notification_sent_at=detected + timedelta(hours=40),
                final_report_deadline=detected + timedelta(days=30),
                final_report_sent_at=detected + timedelta(days=18),
                description=(
                    "Injection su un form di contatto legacy ha esposto un numero "
                    "limitato di indirizzi email. Vettore rimosso, ciclo Art. 23 "
                    "completato (early warning, notifica 72h, relazione finale)."
                ),
                affected_systems="Sito corporate (www.beta-bank.example)",
                impact_category="reputational",
                estimated_impact_level=4,  # minor
                users_affected_count=340,
                containment_actions="Form vulnerabile disabilitato; WAF aggiornato.",
                eradication_actions="Refactoring del form con validazione server-side.",
                recovery_actions="Ripristino servizio; notifica agli interessati.",
                lessons_learned="Introdurre code review di sicurezza sui form pubblici.",
                csirt_reference_id="CSIRT-IT-DEMO-0042",
                csirt_taxonomy_code="INFORMATION-CONTENT-SECURITY",
            ),
        ]
    return []


def _vendors_for(now, org):
    return [
        dict(organization_id=org.id, name="Nord ICT Services", vendor_type="ict_service",
             criticality=1, status="active", contact_email="soc@nord-ict.example",
             services_provided="SOC gestito, monitoraggio 24/7",
             data_access_level="high", geographic_location="EU",
             has_security_certification="ISO 27001", security_score=78,
             acn_rilevanza_art18=True,
             next_audit_date=now + timedelta(days=120)),
        dict(organization_id=org.id, name="Cloud Fabric EU", vendor_type="cloud_provider",
             criticality=1, status="active", contact_email="security@cloudfabric.example",
             services_provided="IaaS, storage",
             data_access_level="medium", geographic_location="EU",
             has_security_certification="ISO 27001, SOC 2", security_score=85,
             acn_rilevanza_art18=True,
             next_audit_date=now + timedelta(days=210)),
        dict(organization_id=org.id, name="LegacyPatch Srl", vendor_type="ict_service",
             criticality=2, status="review", contact_email="support@legacypatch.example",
             services_provided="Manutenzione software legacy",
             data_access_level="low", geographic_location="EU",
             has_security_certification=None, security_score=48,
             acn_rilevanza_art18=False,
             risk_notes="Nessuna certificazione; audit di sicurezza in ritardo.",
             next_audit_date=now - timedelta(days=30)),
    ]


def _bia_for(org, sector):
    return [
        dict(organization_id=org.id, name=f"Erogazione servizio primario ({sector})",
             process_owner="Direzione Operations", department="Operations",
             criticality_level=1, rto_hours=4, rpo_hours=1, mtpd_hours=8,
             impact_financial=5, impact_operational=5, impact_reputational=4,
             impact_regulatory=5, impact_safety=4,
             acn_servizio_essenziale=True, has_bcp=True, has_drp=True),
        dict(organization_id=org.id, name="Fatturazione e incasso clienti",
             process_owner="CFO", department="Finance",
             criticality_level=2, rto_hours=24, rpo_hours=8, mtpd_hours=72,
             impact_financial=4, impact_operational=3, impact_reputational=2,
             impact_regulatory=3, impact_safety=1,
             acn_servizio_essenziale=False, has_bcp=True, has_drp=False),
    ]


async def enrich():
    import os
    import secrets

    from passlib.context import CryptContext
    from sqlalchemy import delete, select

    from app.database import async_session_factory, engine, Base
    from app.models.organization import Organization
    from app.models.membership import Membership
    from app.models.user import User
    from app.models.asset import Asset
    from app.models.incident import Incident
    from app.models.notification_channel import NotificationChannel
    from app.models.vendor import Vendor
    from app.models.bia import BusinessProcess
    from app.routers.governance import GovernanceItem, CHECKLIST_TEMPLATE

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    now = datetime.now(timezone.utc)

    demo_password = os.environ.get("DEMO_PASSWORD")
    if not demo_password:
        demo_password = secrets.token_urlsafe(12)
        print(f"[warn] DEMO_PASSWORD not set — MSSP operator password: {demo_password}")

    async with async_session_factory() as db:
        orgs = (await db.execute(select(Organization))).scalars().all()
        by_slug = {o.slug: o for o in orgs}
        if not by_slug:
            print("[ERROR] No demo orgs found — run scripts/seed_demo.py first.")
            return

        # ── 1. Governance checklist for EVERY demo org ──────────────────
        gov_created = 0
        for org in orgs:
            await db.execute(
                delete(GovernanceItem).where(GovernanceItem.organization_id == org.id)
            )
            for idx, (item_id, priority, title, description, ref, subpara) in enumerate(
                CHECKLIST_TEMPLATE
            ):
                status = "not_started"
                if item_id in GOV_DONE:
                    status = "done"
                elif item_id in GOV_IN_PROGRESS:
                    status = "in_progress"
                db.add(GovernanceItem(
                    organization_id=org.id, item_id=item_id, priority=priority,
                    title=title, description=description, nis2_reference=ref,
                    subparagraph=subpara, status=status, sort_order=idx,
                ))
                gov_created += 1
        print(f"[gov] {gov_created} governance items across {len(orgs)} orgs "
              f"(Art. 21.2.x left not_started for the live sync-risk demo)")

        # ── 2/3/4. Narrative overlay on the hero orgs ───────────────────
        for slug in HERO_SLUGS:
            org = by_slug.get(slug)
            if org is None:
                print(f"[warn] hero org '{slug}' not found — skipped")
                continue

            # admin user of the org (reported_by for incidents)
            m = (await db.execute(
                select(Membership).where(Membership.organization_id == org.id)
                .order_by(Membership.created_at).limit(1)
            )).scalar_one_or_none()
            if m is None:
                print(f"[warn] '{slug}' has no membership — skipped")
                continue
            user_id = m.user_id

            assets = (await db.execute(
                select(Asset).where(Asset.organization_id == org.id)
            )).scalars().all()
            asset_ids = [str(a.id) for a in assets]
            sector = (org.settings or {}).get("sector", "N/A")

            # wipe the rows we manage for this org, then recreate (idempotent)
            for model in (Incident, NotificationChannel, Vendor, BusinessProcess):
                await db.execute(
                    delete(model).where(model.organization_id == org.id)
                )

            for inc in _incidents_for(now, slug, org, user_id, asset_ids):
                db.add(Incident(**inc))

            # notification channels (hero orgs only)
            db.add(NotificationChannel(
                organization_id=org.id, channel_type="slack", name="SOC — #nis2-alerts",
                config={"webhook_url": "https://hooks.example.com/services/T000/B000/demo"},
                events=["incident.deadline_approaching", "incident.created", "finding.critical"],
                is_active=True,
            ))
            db.add(NotificationChannel(
                organization_id=org.id, channel_type="email", name="CISO + DPO",
                config={"recipients": [f"ciso@{slug}.example", f"dpo@{slug}.example"]},
                events=["incident.deadline_approaching", "incident.created"],
                is_active=True,
            ))

            for v in _vendors_for(now, org):
                db.add(Vendor(**v))
            for bp in _bia_for(org, sector):
                db.add(BusinessProcess(**bp))

            print(f"[hero] {org.name}: incidents + 2 channels + 3 vendors + 2 BIA processes")

        # ── 5. MSSP operator — one login, member of all 10 demo orgs ────
        # Idempotent: drop the operator's memberships + user, recreate.
        existing_op = (await db.execute(
            select(User).where(User.email == MSSP_OPERATOR_EMAIL)
        )).scalar_one_or_none()
        if existing_op is not None:
            await db.execute(
                delete(Membership).where(Membership.user_id == existing_op.id)
            )
            await db.delete(existing_op)
            await db.flush()

        operator = User(
            email=MSSP_OPERATOR_EMAIL,
            password_hash=pwd_context.hash(demo_password),
            full_name="MSSP Operator (demo)",
            email_verified=True,
            is_active=True,
            locale="it",
        )
        db.add(operator)
        await db.flush()

        joined = 0
        for slug in DEMO_SLUGS:
            org = by_slug.get(slug)
            if org is None:
                continue
            db.add(Membership(
                user_id=operator.id,
                organization_id=org.id,
                role="admin",
                accepted_at=now,
            ))
            joined += 1
        print(f"[mssp] operator {MSSP_OPERATOR_EMAIL} → admin of {joined} demo orgs "
              f"(password: {demo_password})")

        await db.commit()

    # ── Summary + clock state at seed time ──────────────────────────────
    print("\n" + "=" * 64)
    print("NARRATIVE SEED DONE — Art. 23 clocks (relative to seed time):")
    print("=" * 64)
    hero_g = timedelta(hours=32)
    hero_e = timedelta(hours=18)
    print(f"  Gamma Power  → 72h notification deadline in ~{int(hero_g.total_seconds()//3600)}h "
          f"(early warning already sent)  ← THE hero countdown")
    print(f"  Eta Water    → 24h early-warning deadline in ~{int(hero_e.total_seconds()//3600)}h "
          f"(not yet sent)")
    print(f"  Beta Bank    → closed incident (full Art. 23 lifecycle)")
    print(f"\n  Canale-first login (all 10 clients in the org switcher):")
    print(f"    {MSSP_OPERATOR_EMAIL}  /  {demo_password}")
    print("\n  Re-run this script right before filming to refresh the clocks.")
    print("  On camera: open a hero org → click POST /governance/sync-risk")
    print("  to escalate the Art. 21.2.x items live from the scanner findings.\n")


if __name__ == "__main__":
    asyncio.run(enrich())
