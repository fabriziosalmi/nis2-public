# NIS2 Governance Checklist: 30 Priorities

## 📖 How to Use This Document
This checklist is designed to be a living document for Compliance Officers, CISOs, and IT Managers.

1.  **Assessment**: Go through each item and mark the current status.
2.  **Assignment**: Assign an owner to each missing item (e.g., "IT Manager" for Backups, "Legal" for Contracts).
3.  **Tracking**: Review this document monthly during board or management meetings.
4.  **Evidence**: Store proofs of compliance (PDFs, screenshots, logs) in a secure repository referenced here.

This checklist is ordered by "Survival and Legal Compliance" logic: first, the items that save you from immediate sanctions and operational halts, then structure, and finally optimization.

## 🔗 Official & Helpful References
- **NIS2 Directive (EU 2022/2555)**: [Official Text (EUR-Lex)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
- **ACN Portal (Italy)**: [Registration Login](https://portale.acn.gov.it/login)
- **ENISA Guidelines**: [Technical Implementation Guidance](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance)
- **SANS Policy Templates**: [Information Security Policy Templates](https://www.sans.org/information-security-policy/)
- **Community Resources**: [Awesome NIS2 Directive Repo](https://github.com/CyberAlbSecOP/Awesome_NIS2_Directive)

---

## 🔴 CRITICAL PRIORITY (Must-Have by Deadlines)
*Without these, the company is legally exposed or technically defenseless.*

- [ ] **Scoping Analysis**: Definitive confirmation if the company is an "Essential" or "Important" entity under Legislative Decree 138/2024 (or local transposition).
- [ ] **ACN Portal Registration**: Has the company registered on the National Cybersecurity Agency portal? (Primary formal obligation).
- [ ] **Governance - Board Responsibility**: Have the Board/Directors formally assumed responsibility for cybersecurity (approval minutes)?
- [ ] **Governance - Management Training**: Have the governing bodies attended the mandatory cybersecurity training course?
- [ ] **MFA (Multi-Factor Authentication)**: Is it active on all remote accesses (VPN, Cloud) and privileged accounts (Admin)?
- [ ] **Immutable/Offline Backups**: Is there a critical data copy disconnected from the network or immutable (anti-ransomware)?
- [ ] **Incident Notification Procedure (24h/72h)**: Is there a written procedure explaining who calls the CSIRT within 24h in case of a severe attack?
- [ ] **Asset Inventory**: Is there an updated list of hardware, software, and data? (You cannot protect what you don't know you have).
- [ ] **Vulnerability Management (Patching)**: Are critical security patches installed within certain timeframes (e.g., 48-72h from release)?
- [ ] **Cybersecurity Budget**: Has a specific and adequate budget been allocated for NIS2 compliance?

## 🟠 HIGH PRIORITY (Core Processes)
*These measures define the company's ability to manage risk.*

- [ ] **Risk Assessment**: Has a formal cyber risk analysis been conducted on all critical assets?
- [ ] **Information Security Policy**: Is there an approved "master" document dictating corporate security rules?
- [ ] **Supplier Mapping (Supply Chain)**: Is there a list of critical suppliers (MSP, Software, Cloud)?
- [ ] **Supply Chain Security**: Have security requirements and incident notification clauses been included in supplier contracts?
- [ ] **Incident Response Plan (IR Plan)**: Beyond notification, is there a technical plan on how to contain and eradicate an attack?
- [ ] **Business Continuity Plan (BCP)**: Are there procedures to continue working (even manually) if IT is down?
- [ ] **Disaster Recovery Plan (DR)**: Has IT system restoration after a disaster been defined and tested?
- [ ] **Employee Training (Awareness)**: Is there a continuous anti-phishing training program for all staff?
- [ ] **Backup Testing**: Is a data restoration test performed at least every 6 months?
- [ ] **Access Control (Least Privilege)**: Do employees have only the permissions strictly necessary to work (no local Admins everywhere)?

## 🔵 MEDIUM PRIORITY (Optimization and Hygiene)
*Technical and organizational measures necessary for complete compliance.*

- [ ] **Network Segmentation**: Is the production network (OT) or critical departments separated from the office/guest network?
- [ ] **Onboarding/Offboarding**: Is there an automatic checklist to revoke access when an employee leaves the company?
- [ ] **Encryption**: Are sensitive data encrypted when stored (at rest) and when traveling (in transit)?
- [ ] **Cryptographic Key Management**: Are encryption keys managed securely and separated from data?
- [ ] **Logging and Monitoring**: Are system logs collected centrally and analyzed to detect anomalies?
- [ ] **Security in Development/Acquisition**: Are security requirements evaluated before buying new software or developing code?
- [ ] **Secure Communications**: Are secure systems used for emergency communications (e.g., Signal/Teams protected) if corporate email is down?
- [ ] **Internal Audits**: Are periodic checks planned to verify that procedures are respected?
- [ ] **Vulnerability Assessment/Pen Test**: Is a technical vulnerability scan performed at least annually?
- [ ] **End-to-End Encryption Usage**: (Where applicable) implementation of advanced measures for protecting confidential communications.
