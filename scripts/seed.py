"""Seed script for development database."""
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add packages to path
sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "api"))

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def seed():
    from app.database import Base, async_session_factory, engine
    from app.models import (
        Asset,
        Finding,
        Membership,
        Organization,
        Scan,
        User,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    import os
    import secrets
    env = os.environ.get("ENVIRONMENT", "development")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        if env == "production":
            raise RuntimeError(
                "Refusing to seed in production without a custom ADMIN_PASSWORD environment variable set."
            )
        admin_password = secrets.token_urlsafe(16)
        print(f"[WARNING] No ADMIN_PASSWORD env var set. Generated a secure random admin password: {admin_password}")

    async with async_session_factory() as db:
        # Demo user
        user = User(
            email="admin@nis2.local",
            password_hash=pwd_context.hash(admin_password),
            full_name="NIS2 Admin",
            email_verified=True,
            is_active=True,
            locale="it",
        )
        db.add(user)
        await db.flush()

        # Demo org
        org = Organization(
            name="NIS2 Demo Corp",
            slug="nis2-demo",
            plan="free",
            max_scans_per_month=100,
        )
        db.add(org)
        await db.flush()

        # Membership
        membership = Membership(
            user_id=user.id,
            organization_id=org.id,
            role="admin",
            accepted_at=datetime.now(timezone.utc),
        )
        db.add(membership)

        # Demo assets
        assets_data = [
            ("Production Website", "domain", "example.com"),
            ("Staging Server", "domain", "staging.example.com"),
            ("API Gateway", "domain", "api.example.com"),
            ("Mail Server", "domain", "mail.example.com"),
            ("Office Network", "cidr", "192.168.1.0/24"),
            ("DMZ Range", "cidr", "10.0.1.0/24"),
        ]
        assets = []
        for name, target_type, target_value in assets_data:
            asset = Asset(
                organization_id=org.id,
                name=name,
                target_type=target_type,
                target_value=target_value,
                tags=["demo"],
                is_active=True,
            )
            db.add(asset)
            assets.append(asset)
        await db.flush()

        # Demo completed scan
        scan = Scan(
            organization_id=org.id,
            created_by=user.id,
            name="Initial Compliance Audit",
            status="completed",
            scan_type="full",
            total_score=73,
            hosts_scanned=6,
            hosts_alive=5,
            findings_critical=2,
            findings_high=5,
            findings_medium=12,
            findings_low=8,
            config_snapshot={
                "name": "Initial Compliance Audit",
                "domains": ["example.com", "staging.example.com"],
                "ip_ranges": ["192.168.1.0/24"],
                "features": {
                    "dns_checks": True,
                    "web_checks": True,
                    "port_scan": True,
                    "whois_checks": True,
                },
            },
            compliance_matrix={
                "art21_a": {"status": "Automated", "description": "Policies on risk analysis"},
                "art21_b": {"status": "Automated", "description": "Incident handling"},
                "art21_c": {"status": "Partially Automated", "description": "Business continuity"},
                "art21_d": {"status": "Automated", "description": "Supply chain security"},
                "art21_e": {"status": "Automated", "description": "Network security"},
                "art21_f": {"status": "Manual Verification Required", "description": "Vulnerability handling"},
                "art21_g": {"status": "Automated", "description": "Cybersecurity assessment"},
                "art21_h": {"status": "Partially Automated", "description": "Cyber hygiene"},
                "art21_i": {"status": "Automated", "description": "Cryptography"},
                "art21_j": {"status": "Manual Verification Required", "description": "Human resources security"},
            },
            executive_summary="The initial compliance audit reveals moderate compliance with NIS2 requirements.",
            started_at=datetime(2026, 3, 27, 10, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 3, 27, 10, 15, 0, tzinfo=timezone.utc),
            duration_seconds=900,
        )
        db.add(scan)
        await db.flush()

        # Demo findings
        findings_data = [
            ("CRITICAL", "ENCRYPTION", "TLS 1.0 supported on port 443", "example.com", "Disable TLS 1.0"),
            ("CRITICAL", "ACCESS CONTROL", "SMB port 445 exposed to internet", "192.168.1.1", "Block port 445 at firewall"),
            ("HIGH", "ENCRYPTION", "Expired TLS certificate", "staging.example.com", "Renew certificate"),
            ("HIGH", "CYBER HYGIENE", "Missing HSTS header", "example.com", "Add Strict-Transport-Security header"),
            ("HIGH", "RESILIENCE", "No WAF/CDN detected", "api.example.com", "Deploy WAF"),
            ("HIGH", "INCIDENT HANDLING", "No security.txt found", "example.com", "Add /.well-known/security.txt"),
            ("HIGH", "SECURE COMMUNICATIONS", "SPF record missing", "example.com", "Add SPF TXT record"),
            ("MEDIUM", "RESILIENCE", "DNSSEC not enabled", "example.com", "Enable DNSSEC"),
            ("MEDIUM", "CYBER HYGIENE", "Missing CSP header", "example.com", "Add Content-Security-Policy"),
            ("MEDIUM", "CYBER HYGIENE", "Missing X-Frame-Options", "staging.example.com", "Add X-Frame-Options: DENY"),
            ("MEDIUM", "SUPPLY CHAIN SECURITY", "External scripts without SRI", "example.com", "Add integrity attributes"),
            ("LOW", "CYBER HYGIENE", "Server version disclosed", "api.example.com", "Remove Server header"),
            ("LOW", "ENCRYPTION", "No HTTPS redirect", "staging.example.com", "Configure HTTP->HTTPS redirect"),
        ]

        import hashlib

        for severity, category, message, target, remediation in findings_data:
            fingerprint = hashlib.sha256(f"{category}:{message}:{target}".encode()).hexdigest()
            finding = Finding(
                scan_id=scan.id,
                organization_id=org.id,
                severity=severity,
                category=category,
                message=message,
                target=target,
                remediation=remediation,
                fingerprint=fingerprint,
                status="open",
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
                compliance_article="Art. 21",
            )
            db.add(finding)

        await db.commit()
        print("Seed data created successfully!")
        print(f"  User: admin@nis2.local / {admin_password}")
        print(f"  Org: NIS2 Demo Corp ({org.id})")
        print(f"  Assets: {len(assets)}")
        print(f"  Scans: 1")
        print(f"  Findings: {len(findings_data)}")


if __name__ == "__main__":
    asyncio.run(seed())
