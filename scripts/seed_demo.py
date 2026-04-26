"""
Seed 10 realistic Italian companies for NIS2 compliance demo.
Each company has unique infrastructure, risk profile, and compliance posture.
Run: docker compose -f infra/docker/docker-compose.dev.yml exec api python /app/scripts/seed_demo.py
"""
import asyncio
import hashlib
import random
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "api"))

from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ============================================================
# 10 Italian companies across different NIS2 sectors
# ============================================================
COMPANIES = [
    {
        "name": "Alpha Medical",
        "slug": "san-raffaele",
        "sector": "Healthcare",
        "admin": {"name": "Fab", "email": "fab@alpha-medical.it"},
        "assets": [
            ("Portale Pazienti", "domain", "pazienti.alpha-medical.it"),
            ("Sistema HIS", "domain", "his.alpha-medical.it"),
            ("PACS Imaging", "domain", "pacs.alpha-medical.it"),
            ("Mail Server", "domain", "mail.alpha-medical.it"),
            ("VPN Gateway", "ip", "192.0.2.1"),
            ("Rete Reparto Chirurgia", "cidr", "10.10.1.0/24"),
            ("Rete Laboratorio", "cidr", "10.10.2.0/24"),
        ],
        "score": 58,
        "findings": [
            ("CRITICAL", "ENCRYPTION", "TLS 1.0 attivo sul portale pazienti - dati sanitari esposti", "pazienti.alpha-medical.it", "Disabilitare TLS 1.0/1.1, forzare TLS 1.3"),
            ("CRITICAL", "ACCESS CONTROL", "Porta RDP (3389) esposta su VPN gateway", "192.0.2.1", "Chiudere RDP, usare VPN con MFA"),
            ("CRITICAL", "ENCRYPTION", "Sistema PACS accessibile senza HTTPS", "pacs.alpha-medical.it", "Abilitare HTTPS con certificato valido"),
            ("HIGH", "CYBER HYGIENE", "Header HSTS mancante sul portale pazienti", "pazienti.alpha-medical.it", "Aggiungere Strict-Transport-Security"),
            ("HIGH", "INCIDENT HANDLING", "Nessun security.txt configurato", "pazienti.alpha-medical.it", "Creare /.well-known/security.txt"),
            ("HIGH", "SECURE COMMUNICATIONS", "Record SPF mancante", "alpha-medical.it", "Configurare SPF nel DNS"),
            ("HIGH", "SECURE COMMUNICATIONS", "Record DMARC mancante", "alpha-medical.it", "Configurare DMARC con policy reject"),
            ("HIGH", "RESILIENCE", "Nessun WAF rilevato", "pazienti.alpha-medical.it", "Implementare WAF (Cloudflare/AWS WAF)"),
            ("MEDIUM", "RESILIENCE", "DNSSEC non abilitato", "alpha-medical.it", "Attivare DNSSEC presso il registrar"),
            ("MEDIUM", "CYBER HYGIENE", "Header CSP mancante", "pazienti.alpha-medical.it", "Configurare Content-Security-Policy"),
            ("MEDIUM", "CYBER HYGIENE", "Server version disclosure (Apache/2.4.41)", "his.alpha-medical.it", "Rimuovere header Server"),
            ("MEDIUM", "SUPPLY CHAIN SECURITY", "Script esterni senza SRI", "pazienti.alpha-medical.it", "Aggiungere attributi integrity"),
            ("LOW", "ENCRYPTION", "Redirect HTTP->HTTPS mancante", "pacs.alpha-medical.it", "Configurare redirect 301"),
            ("LOW", "CYBER HYGIENE", "Cookie senza flag Secure", "his.alpha-medical.it", "Aggiungere flag Secure e HttpOnly"),
        ],
    },
    {
        "name": "Beta Bank",
        "slug": "bpv",
        "sector": "Banking/Finance",
        "admin": {"name": "Fab", "email": "fab@beta-bank.it"},
        "assets": [
            ("Home Banking", "domain", "banking.beta-bank.it"),
            ("Corporate Website", "domain", "www.beta-bank.it"),
            ("API Trading", "domain", "api.beta-bank.it"),
            ("PEC Server", "domain", "pec.beta-bank.it"),
            ("ATM Network Gateway", "ip", "192.0.2.10"),
            ("Rete Filiali", "cidr", "172.16.0.0/16"),
        ],
        "score": 82,
        "findings": [
            ("HIGH", "CYBER HYGIENE", "Header X-Frame-Options mancante sull'home banking", "banking.beta-bank.it", "Aggiungere X-Frame-Options: DENY"),
            ("HIGH", "ENCRYPTION", "Cipher suite debole rilevata (TLS_RSA_WITH_AES_128_CBC_SHA)", "api.beta-bank.it", "Rimuovere cipher CBC, usare solo AEAD"),
            ("MEDIUM", "RESILIENCE", "Singolo MX record - nessuna ridondanza email", "beta-bank.it", "Aggiungere MX secondario"),
            ("MEDIUM", "CYBER HYGIENE", "Header Referrer-Policy mancante", "banking.beta-bank.it", "Aggiungere Referrer-Policy: strict-origin"),
            ("MEDIUM", "INCIDENT HANDLING", "security.txt senza campo Expires", "www.beta-bank.it", "Aggiungere campo Expires a security.txt"),
            ("LOW", "CYBER HYGIENE", "Header X-Content-Type-Options mancante", "www.beta-bank.it", "Aggiungere X-Content-Type-Options: nosniff"),
        ],
    },
    {
        "name": "Gamma Power",
        "slug": "enel-dist",
        "sector": "Energy",
        "admin": {"name": "Fab", "email": "fab@gamma-power.it"},
        "assets": [
            ("Portale Clienti", "domain", "clienti.gamma-power.it"),
            ("SCADA Web Interface", "domain", "scada.gamma-power.it"),
            ("Monitoraggio Rete", "domain", "monitoring.gamma-power.it"),
            ("Corporate Site", "domain", "www.gamma-power.it"),
            ("SCADA Controller", "ip", "192.0.2.5"),
            ("Rete OT Cabine", "cidr", "10.100.0.0/16"),
            ("DMZ Industriale", "cidr", "192.168.100.0/24"),
        ],
        "score": 45,
        "findings": [
            ("CRITICAL", "ACCESS CONTROL", "Interfaccia SCADA esposta su internet senza autenticazione", "scada.gamma-power.it", "Rimuovere accesso pubblico, implementare VPN + MFA"),
            ("CRITICAL", "ACCESS CONTROL", "Porta Modbus TCP (502) esposta", "192.0.2.5", "Firewalling immediato, segmentare rete OT"),
            ("CRITICAL", "ACCESS CONTROL", "Porta SSH con password default", "192.0.2.5", "Cambiare credenziali, implementare key-based auth"),
            ("CRITICAL", "ENCRYPTION", "SCADA web senza HTTPS", "scada.gamma-power.it", "Abilitare TLS 1.3"),
            ("HIGH", "RESILIENCE", "Nessun WAF sulla rete esposta", "clienti.gamma-power.it", "Implementare WAF e IPS"),
            ("HIGH", "SUPPLY CHAIN SECURITY", "Firmware controller non aggiornato", "192.0.2.5", "Aggiornare firmware SCADA all'ultima versione"),
            ("HIGH", "INCIDENT HANDLING", "Nessun security.txt", "www.gamma-power.it", "Creare security.txt con contatti CERT"),
            ("HIGH", "SECURE COMMUNICATIONS", "DMARC non configurato", "gamma-power.it", "Implementare DMARC con policy quarantine"),
            ("MEDIUM", "RESILIENCE", "DNSSEC non attivo", "gamma-power.it", "Attivare DNSSEC"),
            ("MEDIUM", "CYBER HYGIENE", "Versione Apache esposta", "monitoring.gamma-power.it", "Nascondere versione server"),
            ("MEDIUM", "CYBER HYGIENE", "Directory listing attivo", "monitoring.gamma-power.it", "Disabilitare directory listing"),
            ("LOW", "ENCRYPTION", "Certificato TLS scade tra 15 giorni", "clienti.gamma-power.it", "Rinnovare certificato, implementare auto-renewal"),
        ],
    },
    {
        "name": "Delta Foods",
        "slug": "delta-foods",
        "sector": "Food Manufacturing",
        "admin": {"name": "Fab", "email": "fab@delta-foods.com"},
        "assets": [
            ("E-commerce B2B", "domain", "b2b.delta-foods.com"),
            ("Corporate Website", "domain", "www.delta-foods.com"),
            ("Supply Chain Portal", "domain", "supply.delta-foods.com"),
            ("Mail Server", "domain", "mail.delta-foods.com"),
            ("SAP Gateway", "ip", "198.51.100.20"),
            ("Rete Stabilimento Parma", "cidr", "10.50.0.0/16"),
        ],
        "score": 74,
        "findings": [
            ("HIGH", "SUPPLY CHAIN SECURITY", "Portale supply chain con script esterni non verificati", "supply.delta-foods.com", "Implementare SRI su tutti gli script esterni"),
            ("HIGH", "ENCRYPTION", "TLS 1.1 ancora supportato", "b2b.delta-foods.com", "Disabilitare TLS 1.0/1.1"),
            ("HIGH", "CYBER HYGIENE", "Missing HSTS header", "www.delta-foods.com", "Aggiungere HSTS con includeSubDomains"),
            ("MEDIUM", "RESILIENCE", "No WAF detected", "b2b.delta-foods.com", "Implementare WAF applicativo"),
            ("MEDIUM", "SECURE COMMUNICATIONS", "SPF record troppo permissivo (+all)", "delta-foods.com", "Restringere SPF a -all"),
            ("MEDIUM", "CYBER HYGIENE", "Cookie di sessione senza SameSite", "b2b.delta-foods.com", "Aggiungere SameSite=Strict"),
            ("LOW", "INCIDENT HANDLING", "security.txt presente ma senza encryption key", "www.delta-foods.com", "Aggiungere chiave PGP a security.txt"),
            ("LOW", "RESILIENCE", "Dominio scade tra 45 giorni", "delta-foods.com", "Rinnovare dominio per almeno 2 anni"),
        ],
    },
    {
        "name": "Epsilon Telco",
        "slug": "epsilon-telco",
        "sector": "Telecommunications",
        "admin": {"name": "Fab", "email": "fab@epsilon-telco.it"},
        "assets": [
            ("Area Clienti", "domain", "areaclienti.epsilon-telco.it"),
            ("Corporate Website", "domain", "www.epsilon-telco.it"),
            ("API Gateway", "domain", "api.epsilon-telco.it"),
            ("DNS Pubblico", "ip", "198.51.100.200"),
            ("NOC Dashboard", "domain", "noc.epsilon-telco.it"),
            ("Core Network", "cidr", "10.5.0.0/16"),
        ],
        "score": 88,
        "findings": [
            ("MEDIUM", "CYBER HYGIENE", "CSP header troppo permissivo (unsafe-inline)", "areaclienti.epsilon-telco.it", "Rimuovere unsafe-inline, usare nonce/hash"),
            ("MEDIUM", "RESILIENCE", "Zone transfer (AXFR) possibile su NS2", "epsilon-telco.it", "Disabilitare AXFR su tutti i nameserver pubblici"),
            ("LOW", "CYBER HYGIENE", "Cookie analytics senza flag HttpOnly", "www.epsilon-telco.it", "Aggiungere HttpOnly a tutti i cookie"),
            ("LOW", "ENCRYPTION", "OCSP stapling non abilitato", "api.epsilon-telco.it", "Abilitare OCSP stapling su Nginx"),
        ],
    },
    {
        "name": "Zeta Rail",
        "slug": "zeta-rail",
        "sector": "Transport",
        "admin": {"name": "Fab", "email": "fab@zeta-rail.it"},
        "assets": [
            ("Acquisto Biglietti", "domain", "acquisti.zeta-rail.it"),
            ("Portale Viaggiatori", "domain", "www.zeta-rail.com"),
            ("API Mobile App", "domain", "api-mobile.zeta-rail.it"),
            ("Intranet Dipendenti", "domain", "intranet.zeta-rail.it"),
            ("Sistema Prenotazioni", "ip", "198.51.100.10"),
            ("Rete Stazioni", "cidr", "10.200.0.0/12"),
        ],
        "score": 71,
        "findings": [
            ("CRITICAL", "ACCESS CONTROL", "Intranet accessibile senza VPN", "intranet.zeta-rail.it", "Limitare accesso a VPN aziendale"),
            ("HIGH", "ENCRYPTION", "Certificato TLS scaduto sull'intranet", "intranet.zeta-rail.it", "Rinnovare certificato immediatamente"),
            ("HIGH", "CYBER HYGIENE", "HSTS mancante su portale acquisti", "acquisti.zeta-rail.it", "Aggiungere HSTS"),
            ("HIGH", "RESILIENCE", "No CDN/WAF sul portale pubblico", "www.zeta-rail.com", "Implementare CDN con WAF"),
            ("MEDIUM", "SECURE COMMUNICATIONS", "DMARC con policy none", "zeta-rail.it", "Portare DMARC da none a quarantine"),
            ("MEDIUM", "SUPPLY CHAIN SECURITY", "jQuery 2.x caricato da CDN esterno senza SRI", "www.zeta-rail.com", "Aggiornare jQuery e aggiungere SRI"),
            ("MEDIUM", "CYBER HYGIENE", "Versione PHP esposta negli header", "intranet.zeta-rail.it", "Rimuovere X-Powered-By"),
            ("LOW", "RESILIENCE", "Singolo nameserver configurato", "zeta-rail.it", "Aggiungere NS secondario e terziario"),
        ],
    },
    {
        "name": "Demoville City Council",
        "slug": "demoville",
        "sector": "Public Administration",
        "admin": {"name": "Fab", "email": "fab@demoville.example"},
        "assets": [
            ("Servizi Online Cittadini", "domain", "servizi.demoville.example"),
            ("Portale Istituzionale", "domain", "www.demoville.example"),
            ("Anagrafe Digitale", "domain", "anagrafe.demoville.example"),
            ("PEC Istituzionale", "domain", "pec.demoville.example"),
            ("WiFi Pubblico Gateway", "ip", "203.0.113.1"),
            ("Rete Uffici", "cidr", "10.0.0.0/8"),
        ],
        "score": 52,
        "findings": [
            ("CRITICAL", "ENCRYPTION", "Anagrafe digitale con TLS 1.0 - dati personali cittadini", "anagrafe.demoville.example", "Aggiornare TLS a 1.2+ immediatamente"),
            ("CRITICAL", "ACCESS CONTROL", "Porta MySQL (3306) esposta su IP pubblico", "203.0.113.1", "Chiudere porta MySQL, accesso solo da rete interna"),
            ("HIGH", "ENCRYPTION", "Certificato self-signed sui servizi online", "servizi.demoville.example", "Ottenere certificato da CA pubblica"),
            ("HIGH", "CYBER HYGIENE", "P.IVA non presente sul sito istituzionale", "www.demoville.example", "Aggiungere P.IVA come richiesto dalla legge"),
            ("HIGH", "INCIDENT HANDLING", "Nessun security.txt", "www.demoville.example", "Creare security.txt conforme RFC 9116"),
            ("HIGH", "CYBER HYGIENE", "Cookie banner non conforme GDPR", "www.demoville.example", "Implementare cookie banner con consenso granulare"),
            ("HIGH", "SECURE COMMUNICATIONS", "SPF e DMARC non configurati", "demoville.example", "Configurare SPF e DMARC"),
            ("MEDIUM", "RESILIENCE", "DNSSEC non abilitato", "demoville.example", "Richiedere attivazione DNSSEC al registrar"),
            ("MEDIUM", "SUPPLY CHAIN SECURITY", "Script Google Analytics caricato senza SRI", "www.demoville.example", "Aggiungere attributi integrity"),
            ("MEDIUM", "CYBER HYGIENE", "Directory /.git/ accessibile", "servizi.demoville.example", "Bloccare accesso a file .git"),
            ("LOW", "RESILIENCE", "No backup DNS rilevato", "demoville.example", "Aggiungere nameserver secondario geograficamente distribuito"),
        ],
    },
    {
        "name": "Eta Water Utility",
        "slug": "aqp",
        "sector": "Water Utility",
        "admin": {"name": "Fab", "email": "fab@eta-water.example"},
        "assets": [
            ("Portale Utenti", "domain", "portale.eta-water.example"),
            ("Corporate Site", "domain", "www.eta-water.example"),
            ("SCADA Depuratori", "domain", "scada-dep.eta-water.example"),
            ("Telemetria Rete", "ip", "203.0.113.50"),
            ("Rete Impianti", "cidr", "192.168.0.0/16"),
        ],
        "score": 41,
        "findings": [
            ("CRITICAL", "ACCESS CONTROL", "SCADA depuratori raggiungibile da internet", "scada-dep.eta-water.example", "Isolare SCADA dalla rete pubblica, VPN obbligatoria"),
            ("CRITICAL", "ENCRYPTION", "Nessun HTTPS su interfaccia SCADA", "scada-dep.eta-water.example", "Implementare TLS 1.3"),
            ("CRITICAL", "ACCESS CONTROL", "Telnet (porta 23) attivo sulla telemetria", "203.0.113.50", "Disabilitare Telnet, usare SSH"),
            ("CRITICAL", "ACCESS CONTROL", "FTP (porta 21) esposto", "203.0.113.50", "Migrare a SFTP/SCP"),
            ("HIGH", "RESILIENCE", "Nessun WAF rilevato", "portale.eta-water.example", "Implementare WAF"),
            ("HIGH", "INCIDENT HANDLING", "Nessun contatto di sicurezza pubblicato", "www.eta-water.example", "Creare security.txt"),
            ("HIGH", "SECURE COMMUNICATIONS", "Nessun record SPF/DMARC", "eta-water.example", "Implementare SPF e DMARC"),
            ("HIGH", "ENCRYPTION", "Certificato TLS scaduto", "portale.eta-water.example", "Rinnovare e automatizzare con Let's Encrypt"),
            ("MEDIUM", "RESILIENCE", "DNSSEC non attivo", "eta-water.example", "Attivare DNSSEC"),
            ("MEDIUM", "CYBER HYGIENE", "Header di sicurezza mancanti (HSTS, CSP, X-Frame)", "portale.eta-water.example", "Aggiungere tutti gli header di sicurezza"),
            ("LOW", "CYBER HYGIENE", "Server espone versione nginx/1.14.0", "www.eta-water.example", "Aggiornare nginx e nascondere versione"),
        ],
    },
    {
        "name": "Theta Consulting",
        "slug": "reply",
        "sector": "IT/Consulting",
        "admin": {"name": "Fab", "email": "admin@theta-consulting.example"},
        "assets": [
            ("Corporate Website", "domain", "www.theta-consulting.example"),
            ("Portale Dipendenti", "domain", "people.theta-consulting.example"),
            ("CI/CD Pipeline", "domain", "ci.theta-consulting.example"),
            ("API Platform", "domain", "api.theta-consulting.example"),
            ("Cloud Gateway", "ip", "203.0.113.150"),
        ],
        "score": 91,
        "findings": [
            ("MEDIUM", "CYBER HYGIENE", "CSP con unsafe-eval per legacy app", "people.theta-consulting.example", "Rimuovere unsafe-eval, refactoring JS"),
            ("LOW", "RESILIENCE", "Solo 2 nameserver configurati", "theta-consulting.example", "Aggiungere terzo NS per ridondanza"),
            ("LOW", "CYBER HYGIENE", "Cookie __ga senza SameSite", "www.theta-consulting.example", "Configurare SameSite=Lax per analytics"),
        ],
    },
    {
        "name": "Iota Confectionery",
        "slug": "iota-confectionery",
        "sector": "Food/Consumer Goods",
        "admin": {"name": "Fab", "email": "fab@iota-confectionery.example"},
        "assets": [
            ("E-commerce Iota Confectionery", "domain", "shop.iota-confectionery.example"),
            ("Corporate Website", "domain", "www.iota-confectionery.example"),
            ("Portale Fornitori", "domain", "suppliers.iota-confectionery.example"),
            ("ERP Gateway", "ip", "203.0.113.210"),
            ("Rete Stabilimento Alba", "cidr", "10.20.0.0/16"),
            ("Rete Logistica", "cidr", "10.30.0.0/16"),
        ],
        "score": 79,
        "findings": [
            ("HIGH", "SUPPLY CHAIN SECURITY", "Portale fornitori con dipendenza jQuery vulnerabile (CVE)", "suppliers.iota-confectionery.example", "Aggiornare jQuery alla versione 3.7+"),
            ("HIGH", "ENCRYPTION", "TLS 1.1 supportato su portale fornitori", "suppliers.iota-confectionery.example", "Disabilitare TLS < 1.2"),
            ("MEDIUM", "CYBER HYGIENE", "HSTS mancante su e-commerce", "shop.iota-confectionery.example", "Configurare HSTS con preload"),
            ("MEDIUM", "RESILIENCE", "CDN rilevato ma WAF non attivo", "www.iota-confectionery.example", "Attivare WAF rules su Cloudflare"),
            ("MEDIUM", "SECURE COMMUNICATIONS", "DMARC con policy none", "iota-confectionery.example", "Aggiornare DMARC a quarantine/reject"),
            ("LOW", "CYBER HYGIENE", "Permissive CORS (Access-Control-Allow-Origin: *)", "suppliers.iota-confectionery.example", "Restringere CORS a domini specifici"),
            ("LOW", "INCIDENT HANDLING", "security.txt senza campo Preferred-Languages", "www.iota-confectionery.example", "Aggiungere Preferred-Languages: it, en"),
        ],
    },
]


async def seed():
    from app.database import async_session_factory, engine, Base
    from app.models.user import User
    from app.models.organization import Organization
    from app.models.membership import Membership
    from app.models.asset import Asset
    from app.models.scan import Scan
    from app.models.finding import Finding

    # Create tables if needed
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        for i, company in enumerate(COMPANIES):
            print(f"\n[{i+1}/10] {company['name']} ({company['sector']})...")

            # Create admin user
            user = User(
                email=company["admin"]["email"],
                password_hash=pwd_context.hash("invaders"),
                full_name=company["admin"]["name"],
                email_verified=True,
                is_active=True,
                locale="it",
            )
            db.add(user)
            await db.flush()

            # Create organization
            org = Organization(
                name=company["name"],
                slug=company["slug"],
                plan="free",
                max_scans_per_month=100,
                settings={"sector": company["sector"]},
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

            # Assets
            asset_ids = []
            domains = []
            ip_ranges = []
            for name, atype, value in company["assets"]:
                asset = Asset(
                    organization_id=org.id,
                    name=name,
                    target_type=atype,
                    target_value=value,
                    tags=[company["sector"].lower().replace("/", "-"), "nis2"],
                    is_active=True,
                )
                db.add(asset)
                await db.flush()
                asset_ids.append(str(asset.id))
                if atype == "domain":
                    domains.append(value)
                else:
                    ip_ranges.append(value)

            # Create scan with realistic timing
            scan_date = datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72))
            duration = random.randint(120, 600)
            completed_at = scan_date + timedelta(seconds=duration)

            n_critical = len([f for f in company["findings"] if f[0] == "CRITICAL"])
            n_high = len([f for f in company["findings"] if f[0] == "HIGH"])
            n_medium = len([f for f in company["findings"] if f[0] == "MEDIUM"])
            n_low = len([f for f in company["findings"] if f[0] == "LOW"])

            scan = Scan(
                organization_id=org.id,
                created_by=user.id,
                name=f"Audit NIS2 - {company['name']}",
                status="completed",
                scan_type="full",
                total_score=company["score"],
                hosts_scanned=len(company["assets"]),
                hosts_alive=len(company["assets"]) - random.randint(0, 1),
                findings_critical=n_critical,
                findings_high=n_high,
                findings_medium=n_medium,
                findings_low=n_low,
                config_snapshot={
                    "name": f"Audit NIS2 - {company['name']}",
                    "domains": domains,
                    "ip_ranges": ip_ranges,
                    "features": {"dns_checks": True, "web_checks": True, "port_scan": True, "whois_checks": True},
                },
                compliance_matrix={
                    "art21_a": {"status": "Automated" if company["score"] > 70 else "Partially Automated", "description": "Politiche di analisi dei rischi"},
                    "art21_b": {"status": "Automated" if n_critical == 0 else "Manual Verification Required", "description": "Gestione degli incidenti"},
                    "art21_c": {"status": "Partially Automated", "description": "Continuita operativa"},
                    "art21_d": {"status": "Automated" if n_high < 3 else "Manual Verification Required", "description": "Sicurezza della catena di approvvigionamento"},
                    "art21_e": {"status": "Automated", "description": "Sicurezza delle reti"},
                    "art21_f": {"status": "Partially Automated", "description": "Gestione delle vulnerabilita"},
                    "art21_g": {"status": "Automated", "description": "Valutazione della cybersicurezza"},
                    "art21_h": {"status": "Automated" if company["score"] > 60 else "Manual Verification Required", "description": "Igiene informatica"},
                    "art21_i": {"status": "Automated" if n_critical == 0 else "Manual Verification Required", "description": "Crittografia"},
                    "art21_j": {"status": "Manual Verification Required", "description": "Sicurezza risorse umane"},
                },
                executive_summary=f"L'audit NIS2 di {company['name']} ({company['sector']}) ha rilevato un punteggio di conformita di {company['score']}/100. "
                    + (f"ATTENZIONE: {n_critical} vulnerabilita critiche richiedono intervento immediato. " if n_critical > 0 else "")
                    + f"Sono stati identificati {len(company['findings'])} findings totali su {len(company['assets'])} asset analizzati.",
                started_at=scan_date,
                completed_at=completed_at,
                duration_seconds=duration,
            )
            db.add(scan)
            await db.flush()

            # Findings
            for severity, category, message, target, remediation in company["findings"]:
                fingerprint = hashlib.sha256(f"{category}:{message}:{target}".encode()).hexdigest()
                # Randomize some statuses for realism
                status = "open"
                if severity == "LOW" and random.random() > 0.5:
                    status = "acknowledged"
                if severity == "MEDIUM" and random.random() > 0.7:
                    status = random.choice(["acknowledged", "in_progress"])

                finding = Finding(
                    scan_id=scan.id,
                    organization_id=org.id,
                    severity=severity,
                    category=category,
                    message=message,
                    target=target,
                    remediation=remediation,
                    fingerprint=fingerprint,
                    status=status,
                    compliance_article="Art. 21 D.Lgs 138/2024",
                    first_seen_at=scan_date,
                    last_seen_at=scan_date,
                )
                db.add(finding)

            print(f"  Score: {company['score']}/100 | Findings: {len(company['findings'])} | Assets: {len(company['assets'])}")

        await db.commit()

    print("\n" + "=" * 60)
    print("DEMO SEED COMPLETATO!")
    print("=" * 60)
    print(f"\n10 aziende create. Password comune: invaders\n")
    print(f"{'Azienda':<35} {'Settore':<20} {'Score':>5} {'Email'}")
    print("-" * 100)
    for c in COMPANIES:
        print(f"{c['name']:<35} {c['sector']:<20} {c['score']:>5} {c['admin']['email']}")
    print()


if __name__ == "__main__":
    asyncio.run(seed())
