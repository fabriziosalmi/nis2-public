# NIS2 Compliance Audit Methodology

## 1. Introduction
This document defines the technical audit methodology used by the **NIS2 Compliance Scanner** to assess the security posture of digital infrastructure in alignment with the **NIS2 Directive (EU 2022/2555)** and its Italian transposition **D.Lgs 138/2024**.

The audit focuses on **Article 21 (Cybersecurity Risk Management Measures)**, specifically translating high-level legal requirements into verifiable technical checks.

---

## 2. Scope & Target Discovery
The scanner operates on a list of defined targets provided in the configuration.
- **Input Types**: IPv4 Addresses, CIDR Ranges, Domain Names.
- **Resolution**:
    - Domains are resolved to their primary A record IPv4 address.
    - CIDR ranges are expanded to individual IPs.
    - Large networks are strictly limited to prevent abuse (configurable limits).
- **Liveness Detection**:
    - Before deep analysis, a simple TCP connect scan is performed on critical ports.
    - Hosts that do not match the liveness criteria are flagged as `Unresponsive` but recorded in the asset inventory.

---

## 3. Technical Checks & Compliance Mapping

The following table details how specific technical findings map to NIS2 requirements.

### 3.1 Exposure & Access Control (Art. 21.2.i)
**Requirement**: "Basic computer hygiene practices and cybersecurity training."
**Requirement**: "Access control policies and asset management."

| Check | Protocol/Port | Technical Rationale | Compliance Impact |
|-------|---------------|---------------------|-------------------|
| **SMB Exposure** | TCP 445 | Block Server Message Block from internet access to prevent ransomware spread (WannaCry-style). | **CRITICAL** (Business Continuity) |
| **RDP Exposure** | TCP 3389 | Block Remote Desktop Protocol to prevent brute-force and credential stuffing. | **CRITICAL** (Access Control) |
| **Database Exposure** | 3306, 5432, 6379, 27017 | Databases (MySQL, Postgres, Redis, Mongo) must never be directly public. | **CRITICAL** (Data Security) |
| **Telnet/FTP** | TCP 23, 21 | Legacy cleartext protocols allow credential interception. | **HIGH** (Legacy Infrastructure) |

### 3.2 Supply Chain & Trust (Art. 21.2.d)
**Requirement**: "Supply chain security including security-related aspects concerning the relationships between each entity and its direct suppliers."

| Check | Protocol | Technical Rationale | Compliance Impact |
|-------|----------|---------------------|-------------------|
| **SSL Expiry** | TLS/X.509 | Expired certificates indicate operational negligence and break trust chains. | **HIGH** (Supply Chain) |
| **DNSSEC** | DNS | Absence of DNSSEC allows DNS spoofing/poisoning, compromising integrity. | **MEDIUM** (Integrity) |

### 3.3 Cryptography & Encryption (Art. 21.2.g)
**Requirement**: "Policies and procedures regarding the use of cryptography and, where appropriate, encryption."

| Check | Protocol | Technical Rationale | Compliance Impact |
|-------|----------|---------------------|-------------------|
| **HTTPS Redirection** | HTTP (80) | All traffic must be encrypted. Cleartext HTTP is unacceptable for modern services. | **LOW** (Cryptography) |
| **TLS Version** | TLS 1.2+ | Support for TLS 1.0/1.1 is considered a vulnerability due to weak ciphers. | **HIGH** (Cryptography) |
| **HSTS Header** | HTTP Header | `Strict-Transport-Security` enforces HTTPS and prevents downgrade attacks. | **MEDIUM** (Cyber Hygiene) |
| **Zone Transfer** | DNS (AXFR) | Allowing full zone transfer leaks internal topology. | **CRITICAL** (Confidentiality) |

---

## 4. Scoring & Risk Methodology

The **Compliance Score (0-100)** is calculated based on a penalty model. Each finding reduces the host's score from a perfect 100.

### 4.1 Severity Penalties
- **CRITICAL**: -50 points (Immediate Action Required)
    - *Example*: SMB exposed to internet.
- **HIGH**: -20 points (Urgent Attention)
    - *Example*: Expired SSL Certificate, Telnet open.
- **MEDIUM**: -10 points (Plan Remediation)
    - *Example*: DNSSEC missing, HSTS missing.
- **LOW**: -5 points (Best Practice)
    - *Example*: No HTTPS redirect.

### 4.2 CVSS Integration
Findings are also assigned a **CVSS v3.1** Base Score to align with industry standard vulnerability management practices.
- **9.0 - 10.0**: Critical
- **7.0 - 8.9**: High
- **4.0 - 6.9**: Medium
- **0.1 - 3.9**: Low

---

## 5. Data Integrity & Reproducibility
To ensure the audit is defensible and reproducible, the scanner implements a "Chain of Custody" system (Phase 3).

1.  **Frozen Configuration**: The exact `config.yaml` used is hashed and stored.
2.  **Raw Evidence**: Actual network responses (HTTP bodies, DNS packets) are captured, not just interpreted.
3.  **Verification Bundle**: A cryptographically signed `.zip` bundle is generated containing all findings and metadata.
4.  **Prometheus Metrics**: Metrics are exported for continuous monitoring integration.

---

## 6. Limitations
- **External View Only**: This audit assesses risk from an external attacker's perspective. It does not verify internal network segmentation or host-based security (EDR/AV).
- **Point-in-Time**: Returns the status at the precise moment of the scan.
- **No Governance Verification**: It cannot verify the existence of written policies, incident response plans, or employee training records (Art 21.2.a, b, c, h).

*Document Version: 1.0 - Generated by NIS2 Compliance Scanner*
