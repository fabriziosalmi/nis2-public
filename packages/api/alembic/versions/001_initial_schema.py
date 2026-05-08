"""Initial schema baseline — P0-01 audit fix.

All 17 tables captured from the existing ORM models as of v2.5.5.
This is a "stamp" migration: it represents the schema that already
exists on every deployed database.  Running `alembic stamp head` on
an existing DB marks it as current without re-running CREATE TABLE.

New databases get the full schema via `alembic upgrade head`.

Revision ID: 001_initial
Revises: None
Create Date: 2026-05-08

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("email", sa.String(256), nullable=False, unique=True, index=True),
        sa.Column("password_hash", sa.String(256), nullable=True),
        sa.Column("full_name", sa.String(256), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("locale", sa.String(10), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- organizations ---
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("slug", sa.String(256), nullable=False, unique=True, index=True),
        sa.Column("settings", postgresql.JSONB(), nullable=True),
    )

    # --- memberships ---
    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("role", sa.String(30), nullable=False, server_default="member"),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("user_id", "organization_id", name="uq_user_org"),
    )

    # --- assets ---
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target_value", sa.String(512), nullable=False),
        sa.Column("pinned_ip", sa.String(45), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.UniqueConstraint("organization_id", "target_type", "target_value", name="uq_org_target"),
    )

    # --- scans ---
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("scan_type", sa.String(30), nullable=False, server_default="full"),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("config_snapshot", postgresql.JSONB(), nullable=True),
        sa.Column("celery_task_id", sa.String(256), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("total_score", sa.Integer(), nullable=True),
        sa.Column("hosts_scanned", sa.Integer(), nullable=True),
        sa.Column("hosts_alive", sa.Integer(), nullable=True),
        sa.Column("findings_critical", sa.Integer(), nullable=True),
        sa.Column("findings_high", sa.Integer(), nullable=True),
        sa.Column("findings_medium", sa.Integer(), nullable=True),
        sa.Column("findings_low", sa.Integer(), nullable=True),
        sa.Column("compliance_matrix", postgresql.JSONB(), nullable=True),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )

    # --- scan_results ---
    op.create_table(
        "scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("is_alive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("open_ports", postgresql.JSONB(), nullable=True),
        sa.Column("http_info", postgresql.JSONB(), nullable=True),
        sa.Column("tls_info", postgresql.JSONB(), nullable=True),
        sa.Column("dns_info", postgresql.JSONB(), nullable=True),
        sa.Column("legal_info", postgresql.JSONB(), nullable=True),
        sa.Column("resilience_info", postgresql.JSONB(), nullable=True),
        sa.Column("whois_info", postgresql.JSONB(), nullable=True),
        sa.Column("secrets_found", postgresql.JSONB(), nullable=True),
        sa.Column("errors", postgresql.JSONB(), nullable=True),
    )

    # --- findings ---
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("target", sa.String(512), nullable=False, server_default=""),
        sa.Column("reference", sa.String(512), nullable=True),
        sa.Column("cvss_base_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(256), nullable=True),
        sa.Column("technical_detail", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("remediation_cost", sa.String(30), nullable=True),
        sa.Column("remediation_effort", sa.String(30), nullable=True),
        sa.Column("compliance_article", sa.String(100), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=True, index=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
    )

    # --- api_keys ---
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("scopes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- notification_channels ---
    op.create_table(
        "notification_channels",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("channel_type", sa.String(30), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )

    # --- audit_logs ---
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
    )

    # --- scan_schedules ---
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- vendors ---
    op.create_table(
        "vendors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("vendor_type", sa.String(50), nullable=False, server_default="ict_service"),
        sa.Column("criticality", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("contact_name", sa.String(255), nullable=True),
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column("contract_ref", sa.String(255), nullable=True),
        sa.Column("contract_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("services_provided", sa.Text(), nullable=True),
        sa.Column("data_access_level", sa.String(30), nullable=False, server_default="none"),
        sa.Column("geographic_location", sa.String(100), nullable=True),
        sa.Column("has_security_certification", sa.String(255), nullable=True),
        sa.Column("last_audit_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_audit_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("security_score", sa.Integer(), nullable=True),
        sa.Column("risk_notes", sa.Text(), nullable=True),
        sa.Column("security_clauses", postgresql.JSONB(), nullable=True),
        sa.Column("acn_codice_servizio", sa.String(100), nullable=True),
        sa.Column("acn_rilevanza_art18", sa.Boolean(), server_default=sa.text("false")),
    )

    # --- incidents ---
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False, index=True),
        sa.Column("reported_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("incident_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="high"),
        sa.Column("status", sa.String(30), nullable=False, server_default="detected"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("early_warning_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("early_warning_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notification_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notification_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("final_report_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("final_report_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("affected_systems", sa.Text(), nullable=True),
        sa.Column("affected_asset_ids", postgresql.JSONB(), nullable=True),
        sa.Column("impact_category", sa.String(100), nullable=False, server_default="operational"),
        sa.Column("estimated_impact_level", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("cross_border", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("supply_chain_impact", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("users_affected_count", sa.Integer(), nullable=True),
        sa.Column("indicators_of_compromise", postgresql.JSONB(), nullable=True),
        sa.Column("evidence_files", postgresql.JSONB(), nullable=True),
        sa.Column("timeline_events", postgresql.JSONB(), nullable=True),
        sa.Column("containment_actions", sa.Text(), nullable=True),
        sa.Column("eradication_actions", sa.Text(), nullable=True),
        sa.Column("recovery_actions", sa.Text(), nullable=True),
        sa.Column("lessons_learned", sa.Text(), nullable=True),
        sa.Column("csirt_reference_id", sa.String(100), nullable=True),
        sa.Column("csirt_taxonomy_code", sa.String(50), nullable=True),
    )

    # --- business_processes ---
    op.create_table(
        "business_processes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("process_owner", sa.String(255), nullable=True),
        sa.Column("department", sa.String(255), nullable=True),
        sa.Column("criticality_level", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("rto_hours", sa.Integer(), nullable=True),
        sa.Column("rpo_hours", sa.Integer(), nullable=True),
        sa.Column("mtpd_hours", sa.Integer(), nullable=True),
        sa.Column("impact_financial", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("impact_operational", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("impact_reputational", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("impact_regulatory", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("impact_safety", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("dependent_asset_ids", postgresql.JSONB(), nullable=True),
        sa.Column("dependent_vendor_ids", postgresql.JSONB(), nullable=True),
        sa.Column("upstream_process_ids", postgresql.JSONB(), nullable=True),
        sa.Column("acn_servizio_essenziale", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("acn_codice_servizio", sa.String(100), nullable=True),
        sa.Column("acn_settore", sa.String(100), nullable=True),
        sa.Column("has_bcp", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("has_drp", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("last_test_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )

    # --- revoked_tokens ---
    op.create_table(
        "revoked_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("jti", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("reason", sa.String(32), nullable=True),
    )
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])

    # --- password_reset_tokens ---
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- governance_items (defined inline in routers/governance.py) ---
    op.create_table(
        "governance_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("item_id", sa.String(20), nullable=False),
        sa.Column("priority", sa.String(20), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("nis2_reference", sa.String(256), nullable=False, server_default=""),
        sa.Column("subparagraph", sa.String(16), nullable=True, index=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="not_started"),
        sa.Column("assigned_to_name", sa.String(256), nullable=True),
        sa.Column("evidence_notes", sa.Text(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
    )

    # --- incident_reports (defined inline in routers/incidents.py) ---
    op.create_table(
        "incident_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_name", sa.String(256), nullable=False),
        sa.Column("entity_sector", sa.String(128), nullable=False),
        sa.Column("contact_email", sa.String(256), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("incident_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(100), nullable=False),
        sa.Column("incident_status", sa.String(50), nullable=False, server_default="ongoing"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("affected_users", sa.Integer(), nullable=True),
        sa.Column("cross_border", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("submission_status", sa.String(50), nullable=False, server_default="draft"),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("report_data", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    # Reverse order — drop dependent tables first.
    op.drop_table("incident_reports")
    op.drop_table("governance_items")
    op.drop_table("password_reset_tokens")
    op.drop_index("ix_revoked_tokens_expires_at", table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
    op.drop_table("business_processes")
    op.drop_table("incidents")
    op.drop_table("vendors")
    op.drop_table("scan_schedules")
    op.drop_table("audit_logs")
    op.drop_table("notification_channels")
    op.drop_table("api_keys")
    op.drop_table("findings")
    op.drop_table("scan_results")
    op.drop_table("scans")
    op.drop_table("assets")
    op.drop_table("memberships")
    op.drop_table("organizations")
    op.drop_table("users")
